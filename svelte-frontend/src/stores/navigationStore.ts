import { writable } from "svelte/store";

//  possible views
export type ViewState = "home" | "settings" | "detailedReport";

// Initialize the store with 'home' as default view
export const currentView = writable<ViewState>("home");
