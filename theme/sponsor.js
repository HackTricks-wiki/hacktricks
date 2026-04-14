;(function sponsor() {
  var sponsorSide = document.querySelector(".sidesponsor")
  var sponsorImg = sponsorSide && sponsorSide.querySelector("img")
  var sponsorTitle = sponsorSide && sponsorSide.querySelector(".sponsor-title")
  var sponsorDescription =
    sponsorSide && sponsorSide.querySelector(".sponsor-description")
  var sponsorCTA = sponsorSide && sponsorSide.querySelector(".sponsor-cta")
  var sponsorSideBsa = document.querySelector(".sidesponsor-bsa")
  var topSponsorBsa = document.querySelector(".topsponsor-bsa")
  var crawlerSlot = document.querySelector(".bsa-crawler-slot")
  var pageviewsSlot = document.querySelector(".bsa-pageviews-slot")

  var bottomSponsor = document.querySelector(".bottomsponsor")
  var bottomSponsorImg = bottomSponsor && bottomSponsor.querySelector("img")
  var bottomSponsorTitle =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-title")
  var bottomSponsorDescription =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-description")
  var bottomSponsorCTA =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-cta")
  var bottomSponsorBsa = document.querySelector(".bottomsponsor-bsa")

  if (
    !sponsorSide ||
    !bottomSponsor ||
    !sponsorSideBsa ||
    !topSponsorBsa ||
    !crawlerSlot ||
    !pageviewsSlot ||
    !bottomSponsorBsa
  ) {
    return
  }

  var BSA_SCRIPT_BASE = "https://cdn4.buysellads.net/pub/hacktricks.js"
  var BSA_FIXED_LEADERBOARD_FALLBACK = {
    brokenId: "bsa-zone_1773065859037-5_123456",
    actualId: "bsa-zone_1770367111944-8_123456",
  }
  var bsaScriptPromise

  function getBsaScriptSrc() {
    return BSA_SCRIPT_BASE + "?" + (new Date() - (new Date() % 600000))
  }

  function ensureBsaScript() {
    if (bsaScriptPromise) {
      return bsaScriptPromise
    }

    var existingScript = document.querySelector(
      'script[src^="' + BSA_SCRIPT_BASE + '"]'
    )
    if (existingScript) {
      bsaScriptPromise = Promise.resolve(existingScript)
      return bsaScriptPromise
    }

    bsaScriptPromise = new Promise(function(resolve, reject) {
      var originalMapGet = Map.prototype.get
      var restoreMapGet = function() {
        Map.prototype.get = originalMapGet
      }

      Map.prototype.get = function(key) {
        if (
          key === BSA_FIXED_LEADERBOARD_FALLBACK.brokenId &&
          !this.has(key) &&
          this.has(BSA_FIXED_LEADERBOARD_FALLBACK.actualId)
        ) {
          return originalMapGet.call(this, BSA_FIXED_LEADERBOARD_FALLBACK.actualId)
        }

        return originalMapGet.call(this, key)
      }

      var bsaOptimize = document.createElement("script")
      bsaOptimize.type = "text/javascript"
      bsaOptimize.async = true
      bsaOptimize.src = getBsaScriptSrc()
      bsaOptimize.onload = function() {
        restoreMapGet()
        resolve(bsaOptimize)
      }
      bsaOptimize.onerror = function(error) {
        restoreMapGet()
        reject(error)
      }
      ;(
        document.getElementsByTagName("head")[0] ||
        document.getElementsByTagName("body")[0]
      ).appendChild(bsaOptimize)
    })

    return bsaScriptPromise
  }

  function setLegacySponsorContent(sponsor, container, nodes) {
    nodes.img.src = sponsor.image_url
    nodes.img.alt = sponsor.name
    nodes.title.textContent = sponsor.name
    nodes.description.innerHTML = sponsor.description
    container.href = sponsor.link
    nodes.cta.textContent = sponsor.cta
    container.style.display = "flex"

    if (sponsor.name.length > 45) {
      nodes.title.style.fontSize = "1.6rem"
    }

    if (sponsor.description.length > 250) {
      nodes.description.style.fontSize = "1.4rem"
    }
  }

  async function fetchLegacySponsor() {
    var currentUrl = encodeURIComponent(window.location.href)
    var url = "https://hacktricks.wiki/sponsor?current_url=" + currentUrl
    var response = await fetch(url, { method: "GET" })

    if (!response.ok) {
      throw new Error("Response status: " + response.status)
    }

    var json = await response.json()
    return json.sponsor
  }

  function renderLegacySideSponsor(sponsor) {
    setLegacySponsorContent(sponsor, sponsorSide, {
      img: sponsorImg,
      title: sponsorTitle,
      description: sponsorDescription,
      cta: sponsorCTA,
    })
  }

  function renderLegacyBottomSponsor(sponsor) {
    setLegacySponsorContent(sponsor, bottomSponsor, {
      img: bottomSponsorImg,
      title: bottomSponsorTitle,
      description: bottomSponsorDescription,
      cta: bottomSponsorCTA,
    })
  }

  async function loadLegacySponsor() {
    var sponsor = await fetchLegacySponsor()
    renderLegacySideSponsor(sponsor)
    renderLegacyBottomSponsor(sponsor)
  }

  function shouldUseBsa() {
    var params = new URLSearchParams(window.location.search)
    var forcedProvider = params.get("ads")

    if (forcedProvider === "bsa") {
      return true
    }

    if (forcedProvider === "legacy") {
      return false
    }

    if (
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "::1"
    ) {
      return true
    }

    return Math.floor(Math.random() * 5) !== 0
  }

  async function loadBsaSponsor() {
    bottomSponsorBsa.style.display = "block"

    if (window.matchMedia("(min-width: 880px)").matches) {
      sponsorSideBsa.style.display = "block"
      topSponsorBsa.style.display = "none"
    } else {
      sponsorSideBsa.style.display = "none"
      topSponsorBsa.style.display = "block"
    }

    await ensureBsaScript()
  }

  async function initSponsor() {
    try {
      var useBsa = shouldUseBsa()
      window.__hacktricksAdsProvider = useBsa ? "bsa" : "legacy"
      console.info("HackTricks ads provider:", window.__hacktricksAdsProvider)

      if (useBsa) {
        await loadBsaSponsor()
        return
      }

      await loadLegacySponsor()
    } catch (error) {
      console.error(error.message || error)

      if (sponsorSideBsa.style.display === "block") {
        sponsorSideBsa.style.display = "none"
      }
      topSponsorBsa.style.display = "none"
      bottomSponsorBsa.style.display = "none"

      try {
        await loadLegacySponsor()
      } catch (legacyError) {
        console.error(legacyError.message || legacyError)
      }
    }
  }

  initSponsor()
})()
