export function removeEmptyBytesAtTheEnd(buffer: Buffer): Buffer {
  let i = buffer.length - 1;
  while (i >= 0 && buffer[i] === 0) {
    i--;
  }
  return buffer.slice(0, i + 1);
}
