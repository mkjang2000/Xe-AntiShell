"use strict";

(() => {
  const preferenceKey = "xeas-theme";
  let theme = "light";
  let buttons = [];

  try {
    const saved = localStorage.getItem(preferenceKey);
    if (saved === "light" || saved === "dark") theme = saved;
  } catch {
    // Storage can be unavailable in embedded or privacy-restricted browsers.
  }

  function applyTheme(next, persist) {
    theme = next;
    document.documentElement.dataset.theme = theme;
    for (const button of buttons) {
      button.setAttribute("aria-pressed", String(theme === "dark"));
    }
    if (persist) {
      try { localStorage.setItem(preferenceKey, theme); } catch {
        // Theme switching still works for this page when persistence is denied.
      }
    }
  }

  // Run in the document head so a saved dark preference does not flash light.
  // A first visit always uses light, irrespective of the operating-system theme.
  applyTheme(theme, false);

  function bindButtons() {
    buttons = [...document.querySelectorAll("[data-theme-toggle]")];
    for (const button of buttons) {
      button.addEventListener("click", () => applyTheme(theme === "dark" ? "light" : "dark", true));
    }
    applyTheme(theme, false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindButtons, {once: true});
  } else {
    bindButtons();
  }
})();
