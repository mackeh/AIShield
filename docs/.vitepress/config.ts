import { defineConfig } from "vitepress";

export default defineConfig({
  title: "AIShield",
  description: "Security scanner for AI-generated code.",
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: [
    /^https:\/\/github\.com\/mackeh\/AIShield\/.*/,
  ],
  head: [
    ["meta", { name: "theme-color", content: "#0f766e" }],
    [
      "meta",
      {
        name: "keywords",
        content:
          "AI security, SAST, SARIF, semgrep, bandit, eslint, code scanning",
      },
    ],
  ],
  themeConfig: {
    siteTitle: "AIShield Docs",
    search: {
      provider: "local",
    },
    nav: [
      { text: "Guide", link: "/getting-started" },
      { text: "CLI", link: "/cli" },
      { text: "Dashboard", link: "/dashboard" },
      { text: "AI Classifier", link: "/ai-classifier" },
      { text: "Integrations", link: "/integrations" },
      { text: "Configuration", link: "/configuration" },
      { text: "CI/CD", link: "/ci-github-actions" },
      { text: "Roadmap", link: "/roadmap" },
    ],
    sidebar: [
      {
        text: "Start",
        items: [
          { text: "Overview", link: "/" },
          { text: "Getting Started", link: "/getting-started" },
          { text: "Architecture", link: "/architecture" },
          { text: "Dashboard and Analytics", link: "/dashboard" },
          { text: "Roadmap", link: "/roadmap" },
        ],
      },
      {
        text: "CLI & Outputs",
        items: [
          { text: "CLI Reference", link: "/cli" },
          { text: "AI Classifier", link: "/ai-classifier" },
          { text: "Output Formats", link: "/output-formats" },
          { text: "Configuration", link: "/configuration" },
        ],
      },
      {
        text: "Operations",
        items: [
          { text: "Integrations", link: "/integrations" },
          { text: "Dashboard", link: "/dashboard" },
          { text: "Analytics Staging Deploy", link: "/analytics-staging" },
          { text: "VS Code Extension", link: "/vscode-extension" },
          { text: "GitHub Actions", link: "/ci-github-actions" },
          { text: "Releasing", link: "/releasing" },
          { text: "Security Policy", link: "https://github.com/mackeh/AIShield/blob/main/SECURITY.md" },
        ],
      },
      {
        text: "Extending AIShield",
        items: [
          { text: "Contributing", link: "/contributing" },
          { text: "Rules Authoring", link: "/rules-authoring" },
        ],
      },
    ],
    socialLinks: [
      { icon: "github", link: "https://github.com/mackeh/AIShield" },
    ],
    editLink: {
      pattern: "https://github.com/mackeh/AIShield/edit/main/docs/:path",
      text: "Edit this page on GitHub",
    },
    outline: {
      level: [2, 3],
      label: "On this page",
    },
    docFooter: {
      prev: "Previous",
      next: "Next",
    },
    footer: {
      message: "Built for secure AI-assisted development workflows.",
      copyright: "Copyright © 2026 AIShield contributors",
    },
  },
});
