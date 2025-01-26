document.addEventListener("DOMContentLoaded", () => {
  const element = document.querySelector(".post-title");
  const targetText = element.textContent.trim();
  let currentText = "";

  console.log("Executing the script");

  function genCharSet() {
    const chars = [];
    for (let i = 32; i <= 126; i++) {
      chars.push(String.fromCharCode(i));
    }
    return chars;
  }

  const characters = genCharSet();

  // 設置動畫總時長（毫秒）
  const totalDuration = 5000; // 5秒
  const totalFrames = targetText.length * characters.length; // 總帧數
  const frameDuration = totalDuration / totalFrames; // 每帧的時長

  function bruteForceEffect(index = 0, currentCharIndex = 0) {
    if (index >= targetText.length) {
      element.textContent = targetText;
      return;
    }

    const targetChar = targetText[index];
    // Animation
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

  console.log("Finish brute forcing!!!");
});
