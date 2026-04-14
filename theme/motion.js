(function () {
  var docEl = document.documentElement;
  var REDUCED_CLASS = "motion-reduced";
  var PAUSED_CLASS = "motion-paused";
  var motionState = {
    mode: "normal",
    reason: "default"
  };

  function setMode(mode, reason) {
    var nextMode = mode === "reduced" ? "reduced" : "normal";
    if (motionState.mode === nextMode && motionState.reason === reason) {
      return;
    }

    motionState.mode = nextMode;
    motionState.reason = reason || motionState.reason;
    docEl.classList.toggle(REDUCED_CLASS, nextMode === "reduced");
    docEl.dataset.motionMode = nextMode;
    window.__hacktricksMotion = {
      mode: motionState.mode,
      reason: motionState.reason,
      shouldReduceMotion: function () {
        return motionState.mode === "reduced";
      }
    };

    document.dispatchEvent(
      new CustomEvent("hacktricks:motionchange", {
        detail: {
          mode: motionState.mode,
          reason: motionState.reason
        }
      })
    );
  }

  function updateVisibilityState() {
    docEl.classList.toggle(PAUSED_CLASS, document.visibilityState === "hidden");
  }

  function getMediaQuery() {
    if (typeof window.matchMedia !== "function") {
      return null;
    }
    return window.matchMedia("(prefers-reduced-motion: reduce)");
  }

  function getDeviceHints() {
    var hints = {
      lowCapability: false,
      hardwareConcurrency: null,
      deviceMemory: null
    };

    if (typeof navigator.hardwareConcurrency === "number") {
      hints.hardwareConcurrency = navigator.hardwareConcurrency;
    }

    if (typeof navigator.deviceMemory === "number") {
      hints.deviceMemory = navigator.deviceMemory;
    }

    hints.lowCapability =
      (hints.hardwareConcurrency !== null && hints.hardwareConcurrency <= 4) ||
      (hints.deviceMemory !== null && hints.deviceMemory <= 4);

    return hints;
  }

  function monitorAnimationHealth() {
    if (
      document.visibilityState === "hidden" ||
      typeof window.requestAnimationFrame !== "function"
    ) {
      return;
    }

    var mediaQuery = getMediaQuery();
    if (mediaQuery && mediaQuery.matches) {
      setMode("reduced", "prefers-reduced-motion");
      return;
    }

    var hints = getDeviceHints();
    var perfState = {
      frameCount: 0,
      firstFrameAt: 0,
      longTaskTime: 0,
      worstFrameGap: 0
    };

    var observer = null;
    if (typeof PerformanceObserver === "function") {
      try {
        observer = new PerformanceObserver(function (list) {
          list.getEntries().forEach(function (entry) {
            perfState.longTaskTime += entry.duration;
          });
        });
        observer.observe({ type: "longtask", buffered: true });
      } catch (error) {
        observer = null;
      }
    }

    var targetDuration = 2500;
    var fpsThreshold = hints.lowCapability ? 50 : 42;
    var longTaskThreshold = hints.lowCapability ? 160 : 240;
    var frameGapThreshold = hints.lowCapability ? 90 : 120;
    var lastFrameAt = 0;

    function finish(now) {
      if (observer) {
        observer.disconnect();
      }

      var elapsed = now - perfState.firstFrameAt;
      if (elapsed <= 0) {
        return;
      }

      var fps = (perfState.frameCount * 1000) / elapsed;
      var shouldReduce =
        fps < fpsThreshold ||
        perfState.longTaskTime > longTaskThreshold ||
        perfState.worstFrameGap > frameGapThreshold;

      if (shouldReduce) {
        setMode("reduced", "runtime-performance");
      }
    }

    function sample(now) {
      if (!perfState.firstFrameAt) {
        perfState.firstFrameAt = now;
      }

      perfState.frameCount += 1;
      if (lastFrameAt) {
        perfState.worstFrameGap = Math.max(
          perfState.worstFrameGap,
          now - lastFrameAt
        );
      }
      lastFrameAt = now;

      if (now - perfState.firstFrameAt >= targetDuration) {
        finish(now);
        return;
      }

      window.requestAnimationFrame(sample);
    }

    window.requestAnimationFrame(sample);
  }

  var mediaQuery = getMediaQuery();
  if (mediaQuery && mediaQuery.matches) {
    setMode("reduced", "prefers-reduced-motion");
  } else {
    setMode("normal", "default");
    if (document.readyState === "complete") {
      window.setTimeout(monitorAnimationHealth, 1200);
    } else {
      window.addEventListener(
        "load",
        function () {
          window.setTimeout(monitorAnimationHealth, 1200);
        },
        { once: true }
      );
    }
  }

  if (mediaQuery) {
    var handlePreferenceChange = function (event) {
      if (event.matches) {
        setMode("reduced", "prefers-reduced-motion");
      } else if (motionState.reason === "prefers-reduced-motion") {
        setMode("normal", "preference-restored");
        window.setTimeout(monitorAnimationHealth, 600);
      }
    };

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handlePreferenceChange);
    } else if (typeof mediaQuery.addListener === "function") {
      mediaQuery.addListener(handlePreferenceChange);
    }
  }

  updateVisibilityState();
  document.addEventListener("visibilitychange", updateVisibilityState);
})();
