document.getElementById("uploadForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const fileInput = document.getElementById("emailInput");
    if (fileInput.files.length === 0) {
        alert("Please select a file.");
        return;
    }

    const file = fileInput.files[0];
    const apiKey = "b226d2bbf0c1d23104c99e14c2c6cb7ec8edf6c03253d40ea77b6701fcd2585f"; // Replace with your VirusTotal API key

    const formData = new FormData();
    formData.append("file", file);

    try {
        // Step 1: Upload File
        const uploadResponse = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: { "x-apikey": apiKey },
            body: formData
        });

        if (!uploadResponse.ok) {
            throw new Error(`Upload Error: ${uploadResponse.statusText}`);
        }

        const uploadData = await uploadResponse.json();
        const analysisId = uploadData.data.id;

        // Step 2: Poll for Results
        await pollForResults(analysisId, apiKey);

    } catch (error) {
        console.error("Error:", error);
        document.getElementById("result").innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
    }
});

// Function to Poll for Analysis Results
async function pollForResults(analysisId, apiKey) {
    const resultDiv = document.getElementById("result");
    resultDiv.innerHTML = `<p>Analyzing... Please wait.</p>`;

    const maxRetries = 10;
    let retries = 0;

    while (retries < maxRetries) {
        try {
            const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                method: "GET",
                headers: { "x-apikey": apiKey }
            });

            if (!response.ok) {
                throw new Error(`Error: ${response.statusText}`);
            }

            const resultData = await response.json();

            if (resultData.data.attributes.status === "completed") {
                displayResult(resultData);
                return;
            }

            retries++;
            await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds before retrying

        } catch (error) {
            console.error("Polling Error:", error);
            resultDiv.innerHTML = `<p style="color: red;">Polling Error: ${error.message}</p>`;
            return;
        }
    }

    resultDiv.innerHTML = `<p style="color: red;">Analysis timed out. Please try again later.</p>`;
}

// Function to Display Results
function displayResult(resultData) {
    const resultDiv = document.getElementById("result");
    const stats = resultData.data.attributes.stats;

    resultDiv.innerHTML = `
        <h3>Scan Results:</h3>
        <p>✅ Harmless: ${stats.harmless}</p>
        <p>⚠️ Suspicious: ${stats.suspicious}</p>
        <p>❗ Malicious: ${stats.malicious}</p>
        <p>❓ Undetected: ${stats.undetected}</p>
        <p>⏱️ Timeouts: ${stats.timeout}</p>
    `;
}
