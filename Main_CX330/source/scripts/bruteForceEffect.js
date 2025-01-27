(function (history) {
  const originalPushState = history.pushState;

  history.pushState = function (state) {
    const element = document.querySelector(".post-title");
    if (element) {
      executeBruteForceEffect(element);
    }
    console.log("URL Changed");
    return originalPushState.apply(history, arguments);
  };
})(window.history);

window.onload = () => {
  const element = document.querySelector(".post-title");
  if (element) {
    executeBruteForceEffect(element);
  }
};

function executeBruteForceEffect(element) {
  const targetText = element.textContent.trim(); // 目標文本
  let currentText = ""; // 當前顯示文本
  const totalDuration = 3000; // 總動畫時長（毫秒）
  const frameDuration = 50; // 每幀的時間間隔（毫秒）

  function genRandomChar() {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?";
    return chars[Math.floor(Math.random() * chars.length)];
  }

  function animate(index = 0) {
    if (index >= targetText.length) {
      element.textContent = targetText; // 最終文本
      return;
    }

    let animationFrame = 0;
    const maxFrames = Math.floor(
      totalDuration / frameDuration / targetText.length,
    ); // 每個字符的動畫幀數

    function animateChar() {
      if (animationFrame >= maxFrames) {
        // 結束動畫，顯示正確字符
        currentText += targetText[index];
        element.textContent = currentText + "|";
        setTimeout(() => animate(index + 1), frameDuration); // 開始下一個字符
        return;
      }

      // 顯示當前隨機字符動畫
      element.textContent = currentText + genRandomChar() + "|";
      animationFrame++;
      setTimeout(animateChar, frameDuration); // 下一幀動畫
    }

    animateChar();
  }

  animate(); // 開始動畫
}
