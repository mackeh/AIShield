import { createHash } from "node:crypto";

export function aiPasteSignalScore(text: string): number {
  let score = 0;
  
  // Heuristic 1: "Here is the code" patterns
  if (/here is the (code|solution|fix)/i.test(text)) score += 2;
  if (/I('ve| have) (updated|fixed|refactored) the code/i.test(text)) score += 2;
  if (/hope this helps/i.test(text)) score += 1;

  // Heuristic 2: Generic placeholder names often used by AI
  const placeholders = ["foo", "bar", "baz", "example", "myFunction", "doSomething"];
  let placeholderCount = 0;
  for (const p of placeholders) {
      if (text.includes(p)) placeholderCount++;
  }
  if (placeholderCount >= 2) score += 1;

  // Heuristic 3: High comment density (AI often over-explains)
  const lines = text.split("\n");
  const commentLines = lines.filter(l => l.trim().startsWith("//") || l.trim().startsWith("#") || l.trim().startsWith("*"));
  if (lines.length > 5 && (commentLines.length / lines.length) > 0.4) score += 1;

  // Heuristic 4: Markdown artifacts (fenced code blocks in plain text paste)
  if (text.includes("```") || text.includes("`")) score += 2;

  return score;
}

export function countLines(text: string): number {
    return text.split(/\r\n|\r|\n/).length;
}

export function shortHash(text: string): string {
    return createHash("sha1").update(text).digest("hex").substring(0, 8);
}
