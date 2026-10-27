export interface IHighlightSegment {
  text: string;
  matched: boolean;
}

/** 转义正则元字符，避免用户输入 `(` 之类的词导致构造失败 */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 把文本切成「命中 / 未命中」片段，模板用 v-for 渲染。
 * 相比 v-html 拼接，天然避免 XSS，也不需要关键字净化。
 */
export function splitHighlight(text: string, keyword: string): IHighlightSegment[] {
  const trimmed = keyword.trim();

  if (!trimmed || !text) {
    return [{ text, matched: false }];
  }

  const pattern = new RegExp(escapeRegExp(trimmed), 'gi');
  const segments: IHighlightSegment[] = [];
  let lastIndex = 0;
  let matched = pattern.exec(text);

  while (matched !== null) {
    if (matched.index > lastIndex) {
      segments.push({ text: text.slice(lastIndex, matched.index), matched: false });
    }

    segments.push({ text: matched[0], matched: true });
    lastIndex = matched.index + matched[0].length;

    if (matched[0].length === 0) {
      pattern.lastIndex += 1;
    }

    matched = pattern.exec(text);
  }

  if (lastIndex < text.length) {
    segments.push({ text: text.slice(lastIndex), matched: false });
  }

  return segments.length > 0 ? segments : [{ text, matched: false }];
}

/** 统计关键词出现次数，用于「命中 N 处」提示 */
export function countMatches(text: string, keyword: string): number {
  return splitHighlight(text, keyword).filter((segment) => segment.matched).length;
}
