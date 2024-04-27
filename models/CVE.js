const mongoose = require("mongoose");
const cvssDataSchema = new mongoose.Schema({
  version: {
    type: String,
  },
  vectorString: String,
  accessVector: {
    type: String,
  },
  accessComplexity: {
    type: String,
  },
  authentication: {
    type: String,
  },
  confidentialityImpact: {
    type: String,
  },
  integrityImpact: {
    type: String,
  },
  availabilityImpact: {
    type: String,
  },
  baseScore: Number,
});

const cvssMetricV2Schema = new mongoose.Schema({
  source: String,
  type: String,
  cvssData: cvssDataSchema,
  baseSeverity: {
    type: String,
  },
  exploitabilityScore: Number,
  impactScore: Number,
  acInsufInfo: Boolean,
  obtainAllPrivilege: Boolean,
  obtainUserPrivilege: Boolean,
  obtainOtherPrivilege: Boolean,
  userInteractionRequired: Boolean,
});

const descriptionSchema = new mongoose.Schema({
  lang: String,
  value: String,
});

const weaknessSchema = new mongoose.Schema({
  source: String,
  type: String,
  description: [descriptionSchema],
});

const cpeMatchSchema = new mongoose.Schema({
  vulnerable: Boolean,
  criteria: String,
  matchCriteriaId: String,
});

const nodeSchema = new mongoose.Schema({
  operator: String,
  negate: Boolean,
  cpeMatch: [cpeMatchSchema],
});

const configurationSchema = new mongoose.Schema({
  nodes: [nodeSchema],
});

const referenceSchema = new mongoose.Schema({
  url: String,
  source: String,
});

const CVEschema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    sourceIdentifier: String,
    published: Date,
    lastModified: Date,
    vulnStatus: String,
    descriptions: [descriptionSchema],
    metrics: {
      cvssMetricV2: [cvssMetricV2Schema],
    },
    weaknesses: [weaknessSchema],
    configurations: [configurationSchema],
    references: [referenceSchema],
  },
  { collection: "cves" }
);

module.exports = mongoose.model("CVE", CVEschema);
