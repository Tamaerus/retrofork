// File: retrofork/packages/client/web/src/routes/browser/index.tsx
import { createFileRoute } from "@tanstack/react-router";
import { useSearch } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

export const Route = createFileRoute("/browser/")({
  component: BrowserView,
  validateSearch: (search: Record<string, unknown>) => {
    return {
      url: typeof search.url === "string" ? search.url : "",
    };
  },
});

function BrowserView() {
  const { url } = useSearch({ from: "/browser/" });
  const [content, setContent] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);

  // Fetch content whenever the URL in search params changes
  useEffect(() => {
    if (url && url.endsWith(".onion")) {
      fetchOnionUrl(url);
    } else if (url) {
      setError("Please enter a valid .onion URL");
      setContent("");
    }
  }, [url]);

  const fetchOnionUrl = async (fetchUrl: string) => {
    setLoading(true);
    setError("");
    setContent("");

    try {
      // Invoke the backend command 'fetch_onion_url' via Tauri IPC
      const response = await invoke("fetch_onion_url", { url: fetchUrl });
      setContent(response as string);
    } catch (err) {
      setError(`Failed to fetch URL: ${err}`);
      setContent("");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 h-full w-full flex flex-col">
      <h2 className="text-2xl font-bold mb-4">Onion Browser</h2>
      <div className="flex-1 overflow-auto border rounded-md p-2 bg-white">
        {loading && <p className="text-gray-500">Loading content...</p>}
        {error && <p className="text-red-500">{error}</p>}
        {content && (
          <div
            dangerouslySetInnerHTML={{ __html: content }}
            className="w-full h-full"
          />
        )}
        {!loading && !error && !content && !url && (
          <p className="text-gray-500">Enter a .onion URL in the sidebar to view content securely.</p>
        )}
      </div>
    </div>
  );
}
