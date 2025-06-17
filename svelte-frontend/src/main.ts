import { mount } from "svelte";
import "./app.css";
import App from "./popup/Main.svelte";

//render the app
const app = mount(App, {
  target: document.getElementById("app")!, //tells the framework where should be rendered.
});

export default app;
