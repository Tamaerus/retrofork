// File: retrofork/packages/client/web/src/routes/browser/index.tsx
import { createFileRoute } from "@tanstack/react-router";
import { useSearch, useRouter, useLocation } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
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
  const search = useSearch({ from: "/browser/" });
  const url = (search as { url?: string }).url || "";
  const router = useRouter();
  const location = useLocation();
  const [content, setContent] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [navigationTrigger, setNavigationTrigger] = useState<number>(0);
  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    console.log("Current location:", location.pathname, "Search:", location.search);
    // Reset state if navigating back to /home to avoid stale state
    if (location.pathname === "/home") {
      setContent("");
      setError("");
      setLoading(false);
      setNavigationTrigger(0);
    }
  }, [location]);

  useEffect(() => {
    console.log("Current search params URL:", url, "Navigation trigger:", navigationTrigger);
    if (url && url.includes(".onion")) {
      fetchOnionUrl(url);
    } else if (url) {
      setError("Please enter a valid .onion URL");
      setContent("");
    }
  }, [url, navigationTrigger]);

  useEffect(() => {
    if (!contentRef.current) return;

    const handleLinkClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      let linkElement = target.closest('a');
      if (linkElement) {
        console.log("Link clicked:", linkElement.getAttribute("data-href") || linkElement.getAttribute("href"), "Target:", linkElement.getAttribute("target"), "Event type:", event.type);
        event.preventDefault();
        event.stopPropagation();
        const href = linkElement.getAttribute("data-href") || linkElement.getAttribute("href");
        if (href && href !== "#") {
          let newUrl = href;
          // Clean up any localhost or invalid prefixes
          if (newUrl.includes("localhost")) {
            newUrl = newUrl.split("url=")[1]?.split("#")[0] || newUrl;
          }
          if (!newUrl.startsWith("http://") && !newUrl.startsWith("https://") && url) {
            const baseUrl = url.split("/").slice(0, 3).join("/"); // Extract protocol://domain.onion
            newUrl = newUrl.startsWith("/") ? `${baseUrl}${newUrl}` : `${url.split("/").slice(0, -1).join("/")}/${newUrl}`;
            console.log("Resolved relative URL:", newUrl);
          }
          // Clean up ./ in paths for cleaner URLs
          newUrl = newUrl.replace(/\/\.\//, "/");
          // Check if the URL contains .onion and is likely a valid Tor URL (no https:// for non-.onion domains)
          if (!newUrl.includes(".onion")) {
            console.log("Invalid URL, must contain .onion:", newUrl);
            return;
          }
          // Prevent navigation to .onion URLs that might not be Tor-compatible (e.g., https://...onion)
          if (newUrl.startsWith("https://") && newUrl.includes(".onion")) {
            console.log("Invalid URL, .onion URLs should use http:// for Tor compatibility:", newUrl);
            setError("Invalid URL: .onion sites must use http://, not https://");
            return;
          }
          setContent("");
          setError("");
          setLoading(true);
          console.log("Navigating to:", newUrl);
          router.navigate({
            to: "/browser/" as any,
            search: { url: newUrl } as any,
            // No replace: true to allow history stack for back navigation
          }).then(() => {
            console.log("Navigation completed for:", newUrl);
            setNavigationTrigger(prev => prev + 1);
          }).catch((err) => {
            console.error("Navigation error:", err);
            setLoading(false);
          });
        } else {
          console.log("No valid href found, ignoring click.");
        }
      }
    };

    const sanitizeLinks = () => {
      if (contentRef.current) {
        const links = contentRef.current.querySelectorAll('a[href]');
        links.forEach((link) => {
          const href = link.getAttribute('href');
          if (href && href !== '#') {
            link.setAttribute('data-href', href);
            link.setAttribute('href', '#');
          }
          if (link.getAttribute('target') === '_blank') {
            link.removeAttribute('target');
          }
        });
        console.log("Sanitized links in DOM:", links.length);
      }
    };

    const observer = new MutationObserver((mutations) => {
      console.log("MutationObserver triggered, checking for new links");
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length || mutation.type === 'attributes') {
          sanitizeLinks();
        }
      });
    });

    console.log("Attaching click listener to content container");
    contentRef.current.addEventListener("click", handleLinkClick, { capture: true });
    observer.observe(contentRef.current, { childList: true, subtree: true, attributes: true });
    sanitizeLinks();

    return () => {
      console.log("Cleaning up click listener and observer");
      contentRef.current?.removeEventListener("click", handleLinkClick, { capture: true });
      observer.disconnect();
    };
  }, [content, url, router]);

  const fetchOnionUrl = async (fetchUrl: string) => {
    setLoading(true);
    setError("");
    setContent("");

    try {
      console.log("Fetching content for URL:", fetchUrl);
      const response = await invoke("fetch_onion_url", { url: fetchUrl });
      const sanitizedContent = (response as string)
        .replace(/target=["']_blank["']/gi, '')
        .replace(/href=["']([^"']+)["']/gi, 'data-href="$1" href="#"');
      setContent(sanitizedContent);
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
            ref={contentRef}
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
