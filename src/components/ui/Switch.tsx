import { useEffect, useState } from "react";

interface SwitchProps {
  checked: boolean;
  onChange?: (checked: boolean) => void;
  title?: string;
  disabled?: boolean;
}

/**
 * 纯 SVG 内绘圆角开关组件（IPA-7 方案）：
 * 轨道与滑块在同一个 44x24 的 SVG viewBox 内部坐标系中绘制，
 * 不依赖任何 CSS translate-x 或盒模型计算——滑块 x=3/23、宽 18，
 * 永远锁定在 43x23 轨道内部，物理机制上不可能冲出轨道。
 * 内置 ✓/− 状态图标。
 *
 * 【APP-10 任务4】挂载帧动画锁：挂载后的第一帧禁用全部过渡动画，
 * 待 requestAnimationFrame 完成（真实状态已落位）后才启用 transition。
 * 这样即使页面 useState(默认值) 首帧渲染与异步加载的真实值不同，
 * 滑块也瞬时落位、绝不播放「先关后开」的滑动动画；用户后续点击
 * 交互时动画照常生效。从物理机制上消灭全 APP 所有开关的切页闪烁。
 */
export default function Switch({
  checked,
  onChange,
  title,
  disabled = false,
}: SwitchProps) {
  // 挂载帧动画锁：false = 挂载首帧（禁用过渡），true = 已稳定（启用过渡）
  const [animReady, setAnimReady] = useState(false);
  useEffect(() => {
    const raf = requestAnimationFrame(() => setAnimReady(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  const trackTransition = animReady
    ? "fill 180ms ease, stroke 180ms ease"
    : "none";
  const thumbTransition = animReady
    ? "x 180ms cubic-bezier(0.4, 0, 0.2, 1)"
    : "none";

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      title={title}
      disabled={disabled}
      onClick={() => !disabled && onChange?.(!checked)}
      style={{ WebkitAppearance: "none", padding: 0 }}
      className={`inline-flex shrink-0 items-center justify-center border-0 bg-transparent align-middle focus:outline-none ${
        disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"
      }`}
    >
      <svg
        width="44"
        height="24"
        viewBox="0 0 44 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="block shrink-0 overflow-hidden rounded-lg"
      >
        {/* 圆角矩形轨道 */}
        <rect
          x="0.5"
          y="0.5"
          width="43"
          height="23"
          rx="7.5"
          fill={checked ? "#6366F1" : "rgb(var(--glass) / 0.12)"}
          stroke={checked ? "#818CF8" : "rgb(var(--glass) / 0.2)"}
          strokeWidth="1"
          style={{ transition: trackTransition }}
        />
        {/* 内部滑块：开启 x=23（23+18=41 <= 43），关闭 x=3 */}
        <rect
          x={checked ? 23 : 3}
          y="3"
          width="18"
          height="18"
          rx="5"
          fill="#FFFFFF"
          style={{ transition: thumbTransition }}
        />
        {/* 滑块中心状态图标：开启 ✓，关闭 − */}
        {checked ? (
          <path
            d="M28.5 12.2L31 14.7L35.8 9.5"
            stroke="#4F46E5"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ) : (
          <path
            d="M9 12H15"
            stroke="#94A3B8"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}
      </svg>
    </button>
  );
}
