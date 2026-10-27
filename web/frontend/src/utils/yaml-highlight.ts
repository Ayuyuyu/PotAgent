function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const KEY_PATTERN = /^(\s*(?:-\s+)?)([A-Za-z_@$][\w.@$-]*)(\s*:)/;
const SCALAR_PATTERN = /^(.*?)(\s+#.*)$/;

function highlightValue(rawValue: string): string {
  const value = rawValue;

  if (!value.trim()) {
    return value;
  }

  // 行尾注释单独着色
  const commentMatch = SCALAR_PATTERN.exec(value);

  if (commentMatch && !/^\s*['"]/.test(value)) {
    const [, head, comment] = commentMatch;

    return `${highlightValue(head)}<span class="yaml-comment">${comment}</span>`;
  }

  const trimmed = value.trim();

  if (/^["'].*["']$/.test(trimmed)) {
    return value.replace(trimmed, `<span class="yaml-string">${trimmed}</span>`);
  }

  if (/^(true|false|null|~)$/i.test(trimmed)) {
    return value.replace(trimmed, `<span class="yaml-literal">${trimmed}</span>`);
  }

  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return value.replace(trimmed, `<span class="yaml-number">${trimmed}</span>`);
  }

  return value;
}

/**
 * 生成轻量 YAML 着色 HTML。
 * 先整体转义再插入 span，因此不存在注入风险；仅用于编辑器高亮层。
 */
export function highlightYaml(source: string): string {
  return source
    .split('\n')
    .map((line) => {
      const escaped = escapeHtml(line);

      if (/^\s*#/.test(escaped)) {
        return `<span class="yaml-comment">${escaped}</span>`;
      }

      const keyMatch = KEY_PATTERN.exec(escaped);

      if (keyMatch) {
        const [, indent, key, colon] = keyMatch;
        const rest = escaped.slice(keyMatch[0].length);

        return `${indent}<span class="yaml-key">${key}</span><span class="yaml-punct">${colon}</span>${highlightValue(rest)}`;
      }

      if (/^\s*-\s?/.test(escaped)) {
        const listMatch = /^(\s*-\s?)(.*)$/.exec(escaped);

        if (listMatch) {
          const [, marker, rest] = listMatch;

          return `<span class="yaml-punct">${marker}</span>${highlightValue(rest)}`;
        }
      }

      return highlightValue(escaped);
    })
    .join('\n');
}
