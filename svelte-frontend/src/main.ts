import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";

//render the app
const app = mount(App, {
  target: document.getElementById("app")!, //tells the framework where should be rendered.
});

export default app;
