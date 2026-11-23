const picker = document.querySelector('#harbor-sample');
const originals = document.querySelector('#sources');
const form = document.querySelector('.toolbar');
picker.addEventListener('change', () => {
  if (picker.value === 'custom') {
    originals.open = true;
    originals.querySelector('textarea')?.focus();
  }
});
form.addEventListener('submit', () => {
  document.querySelector('#work-feedback').textContent = '正在核算…';
});

const verifyForm = document.querySelector('.verify');
verifyForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const output = verifyForm.querySelector('.verify-result');
  const file = verifyForm.querySelector('input[type="file"]')?.files?.[0];
  if (!file) {
    output.textContent = '请选择外审包 JSON 文件。';
    return;
  }
  output.textContent = '正在核对…';
  try {
    const reply = await fetch(verifyForm.action, {method: 'POST', body: new FormData(verifyForm)});
    const result = await reply.json();
    output.textContent = result.valid
      ? `验真通过 · ${result.run_id?.slice(0, 12) ?? ''}`
      : `验真失败 · ${result.code ?? '摘要不一致'}`;
  } catch {
    output.textContent = '验真失败 · 无法连接签发页。';
  }
});
