// Returns the full URL of the active tab (not just the domain)
export async function getActiveTabUrl(): Promise<string | null> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      resolve(url ?? null);
    });
  });
}

// Returns the domain (hostname) from the active tab's URL
export async function getActiveTabDomain(): Promise<string | null> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (!url) {
        resolve(null);
        return;
      }
      try {
        const { hostname } = new URL(url);
        resolve(hostname);
      } catch (error) {
        resolve(null);
      }
    });
  });
}
