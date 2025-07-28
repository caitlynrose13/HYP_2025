import { mount } from "svelte";
import "./app.css";
import App from "./popup/Main.svelte";
import TabView from "./tab/TabView.svelte";

const target = document.getElementById("app")!;

function render() {
  target.innerHTML = "";
  if (window.location.hash === "#/tab") {
    mount(TabView, { target });
  } else {
    mount(App, { target });
  }
}

window.addEventListener("hashchange", render);
render();

export default null;
