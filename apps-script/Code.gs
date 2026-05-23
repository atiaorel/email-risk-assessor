// Backend endpoint for the AWS Lambda phishing-risk analysis service
var BACKEND_URL = PropertiesService.getScriptProperties().getProperty("BACKEND_URL");

// Keep this in sync with MAX_BODY_LEN on the backend
var BODY_LIMIT = 10000;

function buildAddOn(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId = e.messageMetadata.messageId;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  // Extract the email data relevant for our cybersecurity analysis
  var payload = {
    "sender_name": extractName(message.getFrom()),
    "sender_email": extractEmail(message.getFrom()),
    "reply_to": extractEmail(message.getReplyTo()) || "",
    "subject": message.getSubject() || "",
    "body": (message.getPlainBody() || "").substring(0, BODY_LIMIT),
    "auth_results": message.getHeader("Authentication-Results") || "",
    "links": extractLinks(message.getBody()),
    "attachments": getAttachmentsData(message)
  };

  // Send the payload to our backend and retrieve the risk assessment
  var response = sendToBackend(payload);

  // Build the User Interface (UI) to display inside Gmail
  return createCard(response);
}

// --- Helper Functions ---

function extractName(header) {
  var match = header.match(/^([^<]*)</);
  return match ? match[1].trim() : header.trim();
}

function extractEmail(header) {
  if (!header) return "";
  var match = header.match(/<([^>]+)>/);
  return match ? match[1].trim() : header.trim();
}

function extractLinks(htmlBody) {
  var links = [];
  var regex = /href=["'](https?:\/\/[^"']+)["']/g;
  var match;
  while ((match = regex.exec(htmlBody)) !== null) {
    links.push(match[1]);
  }
  return links;
}

function getAttachmentsData(message) {
  var attachments = message.getAttachments();
  return attachments.map(function(att) {
    return { "filename": att.getName() };
  });
}

// --- Communication ---

function sendToBackend(payload) {
  var addonSecret = PropertiesService.getScriptProperties().getProperty("ADDON_SECRET");

  var options = {
    method: 'post',
    contentType: 'application/json',
    headers: {
      'X-Addon-Secret': addonSecret
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    var code = response.getResponseCode();

    if (code !== 200) {
      return analysisError("The analysis service returned an unexpected response.");
    }

    var data = JSON.parse(response.getContentText());

    if (!data || typeof data.score !== "number" || !data.verdict) {
      return analysisError("The analysis service returned an unreadable response.");
    }

    return data;
  } catch (error) {
    return analysisError("Could not reach the analysis service.");
  }
}

function analysisError(message) {
  return {
    score: 0,
    verdict: "Analysis unavailable",
    color: "#9E9E9E",
    reasons: [message],
    recommendation: "We could not analyze this email. Treat it with caution until it can be checked."
  };
}

// --- UI ---

function createCard(data) {
  function ltr(text) {
    return "\u202A" + text + "\u202C";
  }

  function buildGaugeUrl(score, color) {
    var config = {
      type: "radialGauge",
      data: { datasets: [{ data: [score], backgroundColor: color }] },
      options: {
        domain: [0, 100],
        trackColor: "#E0E0E0",
        centerPercentage: 80,
        centerArea: { text: String(score) + "/100", fontColor: color, fontSize: 20 }
      }
    };
    return "https://quickchart.io/chart?w=140&h=140&c=" +
           encodeURIComponent(JSON.stringify(config));
  }

  var score = typeof data.score === "number" ? Math.max(0, Math.min(100, data.score)) : 0;
  var color = data.color || "#9E9E9E";
  var label = data.verdict || "Unknown";

  var card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle(ltr("Phishing Risk Analysis"))
  );

  var section = CardService.newCardSection();

  // Circular gauge (rendered as an image)
  section.addWidget(
    CardService.newImage()
      .setImageUrl(buildGaugeUrl(score, color))
      .setAltText("Risk score " + score + " out of 100")
  );

  section.addWidget(
    CardService.newTextParagraph()
      .setText(ltr("<b><font color='" + color + "'>" + label + "</font></b>"))
  );

  // Divider
  section.addWidget(CardService.newDivider());

  // Recommendation
  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel(ltr("Recommendation"))
      .setText(ltr(data.recommendation))
      .setWrapText(true)
  );

  // Divider
  section.addWidget(CardService.newDivider());

  // Show indicators only when there is an actual risk signal
  if (data.reasons && data.reasons.length > 0 && data.score > 0) {
    var title = data.score <= 30 ? "Minor Indicators" : "Risk Indicators";

    section.addWidget(
      CardService.newTextParagraph()
        .setText(ltr("<b>" + title + "</b>"))
    );

    for (var i = 0; i < data.reasons.length; i++) {
      section.addWidget(
        CardService.newDecoratedText()
          .setText(ltr((i + 1) + ". " + data.reasons[i]))
          .setWrapText(true)
      );
    }
  }

  card.addSection(section);
  return card.build();
}

// --- Development / Testing Helpers ---

function testBackendConnection() {
  var testPayload = {
    sender_name: "PayPal Security Team",
    sender_email: "paypal-security-alert@gmail.com",
    reply_to: "attacker@example.com",
    subject: "Urgent: verify your password immediately",
    body: "Your PayPal account has been temporarily suspended. Click here to verify your password.",
    auth_results: "spf=fail dkim=fail dmarc=fail",
    links: ["https://bit.ly/paypal-secure-login"],
    attachments: [{ filename: "invoice.exe" }]
  };

  var result = sendToBackend(testPayload);

  Logger.log("Test result: " + JSON.stringify(result));
}
