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
      bruteForceEffect(index + 1);
    } else {
      const nextCharIndex = (currentCharIndex + 1) % characters.length;
      requestAnimationFrame(() => bruteForceEffect(index, nextCharIndex));
    }
  }
});
