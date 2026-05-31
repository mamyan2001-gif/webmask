import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import logoSrc from "../../icon/anonymus.png";
import "./index.css";

const favicon = document.querySelector("link[rel='icon']") || document.createElement("link");
favicon.rel = "icon";
favicon.type = "image/png";
favicon.href = logoSrc;
if (!favicon.parentNode) document.head.appendChild(favicon);

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
