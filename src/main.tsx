import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./styles/globals.css";
import { currentUiLang } from "./utils/errorSanitizer";

/** 【APP24 任务4.4】顶层防黑屏 ErrorBoundary：React 18 中任何子组件渲染
 *  期抛出未捕获异常会直接卸载整个 #root，屏幕变成纯黑背景色。此兜底
 *  在异常时显示错误详情与「重新加载界面」按钮，永不允许黑屏。 */
class RootErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[RootErrorBoundary]", error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (error) {
      return (
        <div
          style={{
            minHeight: "100vh",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: 24,
            background: "#0B0E14",
            color: "#f1f5f9",
            fontFamily: "system-ui, sans-serif",
          }}
        >
          <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 12 }}>
            {currentUiLang() === "zh" ? "界面遇到短暂异常" : "Temporary Interface Issue"}
          </div>
          <div
            style={{
              maxWidth: 420,
              textAlign: "center",
              fontSize: 13,
              lineHeight: 1.7,
              color: "#94a3b8",
              marginBottom: 16,
            }}
          >
            {currentUiLang() === "zh"
              ? "界面渲染未能完成，请点击下方按钮重新加载。详细排查信息已记录至「运行日志」。"
              : "The interface failed to finish rendering. Please reload below. Diagnostics have been written to Logs."}
          </div>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              padding: "10px 24px",
              borderRadius: 8,
              border: "none",
              background: "#3b82f6",
              color: "#fff",
              fontSize: 14,
              fontWeight: 500,
              cursor: "pointer",
            }}
          >
            重新加载界面 / Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

/** 【APP59 任务3.2】前端防线（仅生产构建生效）：屏蔽右键菜单与开发者工具
 *  快捷键（F12 / Ctrl+Shift+I|J|C / Cmd+Option+I|J|C），阻断「零门槛
 *  篡改前端状态」的路径。业务功能与调试构建完全不受影响。 */
function installFrontendGuard() {
  // Vite 开发服务器（localhost / 127.0.0.1）下不介入，保证调试体验
  const host = window.location.hostname;
  if (host === "localhost" || host === "127.0.0.1") return;
  document.addEventListener("contextmenu", (e) => e.preventDefault());
  document.addEventListener(
    "keydown",
    (e) => {
      const key = e.key.toLowerCase();
      const devtoolsCombo =
        key === "f12" ||
        ((e.ctrlKey || e.metaKey) && e.shiftKey && (key === "i" || key === "j" || key === "c")) ||
        (e.metaKey && e.altKey && (key === "i" || key === "j" || key === "c"));
      if (devtoolsCombo) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    true,
  );
}

installFrontendGuard();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <HashRouter>
        <App />
      </HashRouter>
    </RootErrorBoundary>
  </React.StrictMode>
);
