export const pageHead = (title: string, description: string) => () => ({
  meta: [
    { title: `${title} · Secure VMS` },
    { name: "description", content: description },
    { property: "og:title", content: `${title} · Secure VMS` },
    { property: "og:description", content: description },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ],
});
