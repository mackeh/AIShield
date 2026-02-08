import * as vscode from "vscode";

export const lensCritical = vscode.window.createTextEditorDecorationType({
  isWholeLine: true,
  backgroundColor: "rgba(220,38,38,0.10)",
  borderColor: "rgba(220,38,38,0.35)",
  borderStyle: "solid",
  borderWidth: "0 0 0 2px",
});

export const lensHigh = vscode.window.createTextEditorDecorationType({
  isWholeLine: true,
  backgroundColor: "rgba(249,115,22,0.10)",
  borderColor: "rgba(249,115,22,0.35)",
  borderStyle: "solid",
  borderWidth: "0 0 0 2px",
});

export const lensMedium = vscode.window.createTextEditorDecorationType({
  isWholeLine: true,
  backgroundColor: "rgba(234,179,8,0.08)",
  borderColor: "rgba(234,179,8,0.30)",
  borderStyle: "solid",
  borderWidth: "0 0 0 2px",
});
