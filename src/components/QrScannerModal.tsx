import { useCallback, useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { Camera, ImagePlus, X } from "lucide-react";

import { importQrOrTextPayload, type ImportOutcome } from "@/api/ipc";
import Spinner from "@/components/ui/Spinner";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";

interface Props {
  open: boolean;
  onClose: () => void;
  onImported: (outcome: ImportOutcome) => void;
}

/** 单帧最大解码尺寸：移动端摄像头 1080p 原图解码太慢，缩到 640 足够识别 */
const MAX_DECODE_EDGE = 640;

/**
 * 【ACP7 任务1】二维码扫码导入弹窗：双引擎
 * 1. 摄像头实时扫描（getUserMedia + requestAnimationFrame + jsQR）
 * 2. 图片文件识别（相册 / 截图 → Canvas → jsQR）
 *
 * 识别成功后交给后端 `import_qr_or_text_payload` 统一智能解析
 * （订阅链接 / 节点 URI / Base64 / YAML），前端不做格式判断。
 */
export default function QrScannerModal({ open, onClose, onImported }: Props) {
  const { t } = useTranslation();
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const handledRef = useRef(false);
  const fileRef = useRef<HTMLInputElement | null>(null);

  const [cameraError, setCameraError] = useState<string | null>(null);
  const [starting, setStarting] = useState(true);
  const [importing, setImporting] = useState(false);

  const stopCamera = useCallback(() => {
    if (rafRef.current != null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  }, []);

  /** 识别到内容 → 交给后端智能导入（一次性） */
  const handleDetected = useCallback(
    async (payload: string) => {
      const text = payload.trim();
      if (!text || handledRef.current) return;
      handledRef.current = true;
      stopCamera();
      setImporting(true);
      try {
        const outcome = await importQrOrTextPayload(text, null);
        if (outcome.kind === "subscription") {
          toast.success(
            t("sub.importSubscriptionSuccess", { count: outcome.nodeCount }),
          );
        } else {
          toast.success(
            t("sub.importSuccess", {
              count: outcome.nodeCount,
              total: outcome.total,
            }),
          );
        }
        onImported(outcome);
        onClose();
      } catch (e) {
        console.error("qr import failed:", e);
        toast.error(t("sub.importFailed", { error: String(e) }));
        handledRef.current = false;
        onClose();
      } finally {
        setImporting(false);
      }
    },
    [onClose, onImported, stopCamera, t],
  );

  /** 摄像头逐帧扫描 */
  const scanFrame = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;
    if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) {
      const scale = Math.min(
        1,
        MAX_DECODE_EDGE / Math.max(video.videoWidth, video.videoHeight),
      );
      const w = Math.max(1, Math.round(video.videoWidth * scale));
      const h = Math.max(1, Math.round(video.videoHeight * scale));
      if (canvas.width !== w) canvas.width = w;
      if (canvas.height !== h) canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (ctx) {
        ctx.drawImage(video, 0, 0, w, h);
        const image = ctx.getImageData(0, 0, w, h);
        const code = jsQR(image.data, w, h, { inversionAttempts: "dontInvert" });
        if (code?.data) {
          void handleDetected(code.data);
          return;
        }
      }
    }
    rafRef.current = requestAnimationFrame(scanFrame);
  }, [handleDetected]);

  useEffect(() => {
    if (!open) return;
    handledRef.current = false;
    setImporting(false);
    setCameraError(null);
    setStarting(true);

    let cancelled = false;
    const start = async () => {
      try {
        const media = navigator.mediaDevices;
        if (!media?.getUserMedia) {
          throw new Error("getUserMedia unavailable");
        }
        const stream = await media.getUserMedia({
          audio: false,
          video: { facingMode: { ideal: "environment" } },
        });
        if (cancelled) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }
        streamRef.current = stream;
        const video = videoRef.current;
        if (video) {
          video.srcObject = stream;
          await video.play().catch(() => undefined);
        }
        setStarting(false);
        rafRef.current = requestAnimationFrame(scanFrame);
      } catch (e) {
        if (cancelled) return;
        const name = (e as { name?: string })?.name ?? "";
        setCameraError(
          name === "NotAllowedError" || name === "SecurityError"
            ? t("sub.scanCameraDenied")
            : t("sub.scanCameraFailed", { error: String(e) }),
        );
        setStarting(false);
      }
    };
    void start();

    return () => {
      cancelled = true;
      stopCamera();
    };
    // scanFrame / t 变化不重启摄像头：仅在弹窗开关时执行
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  /** 图片导入引擎 */
  const handlePickImage = useCallback(
    async (file: File) => {
      setImporting(true);
      try {
        const bitmap = await createImageBitmap(file);
        const scale = Math.min(
          1,
          MAX_DECODE_EDGE * 2 / Math.max(bitmap.width, bitmap.height),
        );
        const w = Math.max(1, Math.round(bitmap.width * scale));
        const h = Math.max(1, Math.round(bitmap.height * scale));
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d", { willReadFrequently: true });
        if (!ctx) throw new Error("canvas unavailable");
        ctx.drawImage(bitmap, 0, 0, w, h);
        bitmap.close?.();
        const image = ctx.getImageData(0, 0, w, h);
        const code = jsQR(image.data, w, h, { inversionAttempts: "attemptBoth" });
        if (!code?.data) {
          setImporting(false);
          toast.error(t("sub.scanNoCode"));
          return;
        }
        await handleDetected(code.data);
      } catch (e) {
        console.error("qr image decode failed:", e);
        setImporting(false);
        toast.error(t("sub.scanInvalidImage"));
      }
    },
    [handleDetected, t],
  );

  if (!open) return null;

  return (
    <div
      className="pointer-events-auto fixed inset-0 z-[999] flex touch-manipulation items-center justify-center bg-black/60 p-4 pb-[calc(env(safe-area-inset-bottom,16px)+16px)]"
      onClick={onClose}
    >
      <div
        className="flex max-h-[86vh] w-full max-w-md flex-col overflow-hidden rounded-2xl border border-border bg-surface"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Camera size={16} className="text-accent" />
            <h3 className="text-sm font-semibold">{t("sub.scanTitle")}</h3>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
            aria-label={t("common.close")}
          >
            <X size={16} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          <p className="mb-3 text-[12px] text-text-secondary">
            {t("sub.scanDesc")}
          </p>

          <div className="relative aspect-square w-full overflow-hidden rounded-xl border border-border bg-black">
            {/* playsInline + muted：iOS WKWebView 内联播放的必要条件 */}
            <video
              ref={videoRef}
              playsInline
              muted
              autoPlay
              className="h-full w-full object-cover"
            />
            <canvas ref={canvasRef} className="hidden" />
            {starting && (
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-black/70 text-[12px] text-white">
                <Spinner size={18} className="text-white" />
                {t("sub.scanCameraStarting")}
              </div>
            )}
            {cameraError && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/80 p-6 text-center text-[12px] leading-relaxed text-white/90">
                {cameraError}
              </div>
            )}
            {importing && (
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-black/70 text-[12px] text-white">
                <Spinner size={18} className="text-white" />
                {t("sub.scanDetected")}
              </div>
            )}
            {!importing && !starting && !cameraError && (
              <div className="pointer-events-none absolute inset-8 rounded-lg border-2 border-white/70" />
            )}
          </div>

          <p className="mt-3 text-[11px] leading-relaxed text-text-secondary/70">
            {t("sub.scanTip")}
          </p>
        </div>

        <div className="shrink-0 border-t border-border p-4">
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) void handlePickImage(file);
            }}
          />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={importing}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-[#007AFF] px-4 py-3 text-[14px] font-bold text-white transition-colors hover:bg-[#0066DD] disabled:opacity-50"
          >
            <ImagePlus size={16} />
            {t("sub.scanPickImage")}
          </button>
        </div>
      </div>
    </div>
  );
}
