// Listen to URL changes
(function (history) {
  const originalPushState = history.pushState;

  history.pushState = function (state) {
    const element = document.querySelector(".post-title");
    if (element) {
      executeBruteForceEffect(element);
    }
    console.log("URL changed");
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
  const targetText = element.textContent.trim();
  const totalDuration = 4000; // ms
  const frameDuration = 50;
  const totalFrame = Math.floor(totalDuration / frameDuration);
  let currentFrame = 0;

  function getRandomChar() {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?";
    return chars[Math.floor(Math.random() * chars.length)];
  }

  function animate() {
    if (currentFrame >= totalFrame) {
      element.textContent = targetText;
      return;
    }

    let displayText = "";
    for (let i = 0; i < targetText.length; i++) {
      if (Math.random() < currentFrame / totalFrames) {
        // Randomly decide whether to display the target character (more and more characters will be fixed as the animation progresses)
        displayText += targetText[i];
      } else {
        displayText += genRandomChar();
      }
    }
    element.textContent = displayText; // + "█";
    currentFrame++;
    setTimeout(animate, frameDuration);
  }

  animate();
}
