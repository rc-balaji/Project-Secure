require("dotenv").config();
const axios = require("axios");
const mongoose = require("mongoose");
const CVE = require("./models/CVE");
const cron = require("node-cron");

const fetchCVEs = async () => {
  try {
    const response = await axios.get(
      "https://services.nvd.nist.gov/rest/json/cves/2.0",
      {
        params: { resultsPerPage: 10 },
      }
    );

    console.log("API Data:", response.data);
    return response.data && response.data.vulnerabilities
      ? response.data.vulnerabilities
      : [];
  } catch (error) {
    console.error("Error fetching CVE data:", error);
    return [];
  }
};

const cleanseData = (data) => {
  // Implement any data cleansing operations here
  return data.map((item) => {
    if (item.cve && item.cve.descriptions) {
      item.cve.descriptions = item.cve.descriptions.filter(
        (desc) => desc.lang === "en"
      );
    }
    return item;
  });
};

const storeCVEs = async (cveData) => {
  try {
    await mongoose.connect(process.env.DB_URI);
    for (let data of cveData) {
      await CVE.updateOne({ id: data.id }, data, { upsert: true });
    }
    console.log(`Updated records in database.`);
  } catch (error) {
    console.error("Error storing CVEs to MongoDB:", error);
  } finally {
    mongoose.disconnect();
  }
};

async function processCVEs() {
  try {
    const data = await fetchCVEs();
    const cleanedData = cleanseData(data);
    const transformedData = cleanedData
      .map((item) => {
        if (!item.cve) {
          console.error("CVE object is undefined.");
          return null;
        }

        return {
          id: item.cve.id,
          sourceIdentifier: item.cve.sourceIdentifier,
          published: new Date(item.cve.published),
          lastModified: new Date(item.cve.lastModified),
          vulnStatus: item.cve.vulnStatus,
          descriptions: item.cve.descriptions,
          metrics: item.cve.metrics,
          weaknesses: item.cve.weaknesses,
          configurations: item.cve.configurations,
          references: item.cve.references,
        };
      })
      .filter((item) => item !== null);

    await storeCVEs(transformedData);
  } catch (error) {
    console.error("Error in processing CVEs:", error);
  }
}

// Schedule the CVE processing task to run periodically
cron.schedule("0 0 * * *", () => {
  // Runs every day at midnight
  console.log("Running scheduled CVE update...");
  processCVEs();
});

processCVEs();
