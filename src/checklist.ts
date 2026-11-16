/** "skip" means not reached because an earlier step failed. */
export type ItemState = "pass" | "fail" | "skip";

export interface ChecklistItem {
  label: string;
  state: ItemState;
  /** What exactly went wrong, e.g. the server's error or the offending grants. */
  details?: string[];
  /** What to do about it: steps or SQL to run. */
  fix?: string[];
}

export interface ChecklistSection {
  title: string;
  items: ChecklistItem[];
}

const SYMBOL: Record<ItemState, string> = { pass: "✔", fail: "✘", skip: "·" };
const ITEM_INDENT = "  ";
const DETAIL_INDENT = "      ";

function renderItem(item: ChecklistItem): string[] {
  const lines = [`${ITEM_INDENT}${SYMBOL[item.state]} ${item.label}`];
  for (const detail of item.details ?? []) lines.push(`${DETAIL_INDENT}${detail}`);
  if (item.fix?.length) {
    lines.push(`${DETAIL_INDENT}fix:`);
    for (const step of item.fix) lines.push(`${DETAIL_INDENT}  ${step}`);
  }
  return lines;
}

/** Printed to stderr so checklists never mix with piped output. */
export function printChecklist(sections: ChecklistSection[]): void {
  const lines = sections.flatMap((section) => [section.title, ...section.items.flatMap(renderItem)]);
  console.error(lines.join("\n"));
}

/** Marks every item after the first failure as skipped. */
export function skipAfterFailure(items: ChecklistItem[]): ChecklistItem[] {
  const firstFailure = items.findIndex((item) => item.state === "fail");
  if (firstFailure === -1) return items;
  return items.map((item, index) =>
    index > firstFailure ? { ...item, state: "skip", details: undefined, fix: undefined } : item,
  );
}
