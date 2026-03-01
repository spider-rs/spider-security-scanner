import { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://security-scanner.spider.cloud",
      lastModified: new Date(),
      changeFrequency: "weekly",
      priority: 1,
    },
  ];
}
