//function to get the domain from the active tabs URL

export async function getActiveTabDomain(): Promise<string | null> {
  return new Promise((resolve) => {
    //wrap chrome.tabs.query in a promise
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      //get active, cureent window tab

      console.log("queried tabs", tabs);
      const url = tabs[0]?.url; //get the first (basically only) tab URL
      if (!url) return resolve(null);
      console.log("no URL found");
      try {
        const { hostname } = new URL(url);
        console.log("Parsed hostname:", hostname);
        resolve(hostname);
      } catch {
        resolve(null);
      }
    });
  });
}
