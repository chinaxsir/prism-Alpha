import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./styles/globals.css";

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
            界面渲染出错 / Rendering error
          </div>
          <pre
            style={{
              maxWidth: "100%",
              maxHeight: 200,
              overflow: "auto",
              fontSize: 12,
              color: "#f87171",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              marginBottom: 16,
            }}
          >
            {error.message}
          </pre>
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

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <HashRouter>
        <App />
      </HashRouter>
    </RootErrorBoundary>
  </React.StrictMode>
);
