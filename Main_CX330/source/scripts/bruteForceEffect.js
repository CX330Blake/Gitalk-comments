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
