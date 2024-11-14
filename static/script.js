// Load history when the page loads
window.addEventListener("load", async () => {
    const response = await fetch("/history");
    const history = await response.json();
    history.forEach(entry => {
        addHistoryEntry(entry.url, entry.prediction, entry.feedback);
    });
});

document.getElementById("predictButton").addEventListener("click", async () => {
    const urlInput = document.getElementById("urlInput");
    const url = urlInput.value;
    if (!url) return;

    showLoading(true);
    const response = await fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    });

    const result = await response.json();
    showLoading(false);
    document.getElementById("result").innerText = result.prediction ? `This URL is ${result.prediction}` : `Error: ${result.error}`;
    
    // Add prediction to history table immediately, with empty feedback
    addHistoryEntry(url, result.prediction, "");

    // Display feedback form
    document.getElementById("feedbackSection").style.display = "block";

    // Handle thumbs up feedback
    document.getElementById("thumbsUp").onclick = async () => {
        await submitFeedback(url, "right");
    };

    // Handle thumbs down feedback
    document.getElementById("thumbsDown").onclick = async () => {
        await submitFeedback(url, "wrong");
    };
});

// Function to submit feedback
async function submitFeedback(url, feedback) {
    const response = await fetch("/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url, feedback: feedback })
    });

    const result = await response.json();
    showToast(result.message);  // Display feedback message in a toast

    // Update feedback in the history table on the frontend
    const historyTable = document.getElementById("history");
    for (let row of historyTable.rows) {
        if (row.cells[0].innerText === url) {
            row.cells[2].innerText = feedback; // Update feedback cell
            break;
        }
    }
    
    // Clear the URL input and feedback section
    document.getElementById("urlInput").value = ""; // Clear URL input
    document.getElementById("result").innerText = ""; // Clear result message
    document.getElementById("feedbackSection").style.display = "none"; // Hide feedback form
}

// Function to show toast notifications
function showToast(message) {
    const toast = document.getElementById("toast");
    toast.innerText = message;
    toast.classList.add("show");

    // Hide the toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}

// Loading animation display function
function showLoading(isLoading) {
    const loading = document.getElementById("loading");
    loading.style.display = isLoading ? "block" : "none";
    if (isLoading) animateDots();
}

// Dots animation
function animateDots() {
    const dots = document.getElementById("dots");
    setInterval(() => {
        dots.innerText = dots.innerText.length < 6 ? dots.innerText + "." : ".";
    }, 500);
}

// Function to add a history entry to the table
function addHistoryEntry(url, result, feedback) {
    const historyTable = document.getElementById("history");

    // Check if the URL is already in the table, skip if found
    for (let row of historyTable.rows) {
        if (row.cells[0].innerText === url) {
            return;
        }
    }

    const row = document.createElement("tr");
    const urlCell = document.createElement("td");
    urlCell.innerText = url;

    const resultCell = document.createElement("td");
    resultCell.innerText = result;

    const feedbackCell = document.createElement("td");
    feedbackCell.innerText = feedback;

    row.appendChild(urlCell);
    row.appendChild(resultCell);
    row.appendChild(feedbackCell);
    historyTable.appendChild(row);
}
