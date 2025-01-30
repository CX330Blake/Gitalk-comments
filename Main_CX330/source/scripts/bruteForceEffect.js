// 監聽 URL 變化
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
    executeBruteForceEffect(element, () => {
      console.log("Finished animation");
    });
  }
};

let isAnimating = false;

function executeBruteForceEffect(element, callback) {
  if (isAnimating) return;
  isAnimating = true;

  const targetText = element.textContent.trim();
  const totalDuration = 4000; // ms
  const frameDuration = 50;
  // const steps = Math.floor(totalDuration / 200);
  const totalFrames = Math.floor(totalDuration / frameDuration);
  let currentFrame = 0;
  let displayArray = Array(targetText.length).fill("");
  let locks = Array(targetText.length).fill(false);

  function genRandomChar() {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?";
    return chars[Math.floor(Math.random() * chars.length)];
  }

  function animate() {
    if (currentFrame >= totalFrames) {
      element.textContent = targetText; // Final text
      isAnimating = false;
      if (callback) callback();
      return;
    }

    // Random unlock chars
    for (let i = 0; i < targetText.length; i++) {
      if (!locks[i]) {
        displayArray[i] = genRandomChar();
      }
    }

    // Count which char to lock
    let charIndexToLock = Math.floor(
      (currentFrame / totalFrames) * targetText.length,
    );
    if (charIndexToLock < targetText.length && !locks[charIndexToLock]) {
      locks[charIndexToLock] = true;
      displayArray[charIndexToLock] = targetText[charIndexToLock];
    }

    element.textContent = displayArray.join(""); // + "█"; // Vim like cursor
    currentFrame++;
    requestAnimationFrame(animate);
  }

  animate(); // Start
}
