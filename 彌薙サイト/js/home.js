document.addEventListener('DOMContentLoaded', () => {
  const items = document.querySelectorAll('.faq-item');

  items.forEach(item => {
    const question = item.querySelector('.faq-question');

    question.addEventListener('click', () => {
      // まず全部閉じる
      items.forEach(i => i.classList.remove('active'));

      // 押したものが閉じてたら開く
      if (!item.classList.contains('active')) {
        item.classList.add('active');
      }
    });
  });
});