const observer = new MutationObserver(() => {
  const element = document.querySelector(".post-title");
  if (element) {
    observer.disconnect();
    executeBruteForceEffect(elemen);
  }
});

observer.observe(document.body, { childList: true, subtree: true });

function executeBruteForceEffect(element) {
  const targetText = element.textContent.trim();
  let currentText = "";

  function genCharSet() {
    const chars = [];
    for (let i = 32; i <= 126; i++) {
      chars.push(String.fromCharCode(i));
    }
    return chars;
  }

  const characters = genCharSet();
  const totalDuration = 5000; // 動畫總時長
  const totalFrames = targetText.length * characters.length;
  const frameDuration = totalDuration / totalFrames;

  function bruteForceEffect(index = 0, currentCharIndex = 0) {
    if (index >= targetText.length) {
      element.textContent = targetText;
      return;
    }

    const targetChar = targetText[index];
    element.textContent =
      currentText +
      characters[currentCharIndex] +
      (index < targetText.length - 1 ? "_" : "");

    if (characters[currentCharIndex] === targetChar) {
      currentText += targetChar;
      setTimeout(() => bruteForceEffect(index + 1), frameDuration);
    } else {
      const nextCharIndex = (currentCharIndex + 1) % characters.length;
      setTimeout(() => bruteForceEffect(index, nextCharIndex), frameDuration);
    }
  }

  bruteForceEffect();
}
