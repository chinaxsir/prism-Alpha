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
 */
export default function Switch({
  checked,
  onChange,
  title,
  disabled = false,
}: SwitchProps) {
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
          style={{ transition: "fill 180ms ease, stroke 180ms ease" }}
        />
        {/* 内部滑块：开启 x=23（23+18=41 <= 43），关闭 x=3 */}
        <rect
          x={checked ? 23 : 3}
          y="3"
          width="18"
          height="18"
          rx="5"
          fill="#FFFFFF"
          style={{ transition: "x 180ms cubic-bezier(0.4, 0, 0.2, 1)" }}
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
          />
        )}
      </svg>
    </button>
  );
}
