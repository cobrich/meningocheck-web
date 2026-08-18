'use strict';

const symptomWeights = Object.freeze({
  fever: 14, headache: 12, neck: 18, photophobia: 8, nausea: 5,
  vomiting: 7, drowsy: 8, confusion: 16, seizures: 18, rash: 14,
  chills: 4, musclepain: 4, jointpain: 4, coldlimbs: 8, unconscious: 20,
  hardwake: 14, speech: 10, breathing: 10,
});

const emergencySymptoms = new Set(['neck', 'confusion', 'seizures', 'unconscious']);

function calculateRisk(symptoms) {
  const selected = [...new Set(symptoms)];
  if (selected.some((id) => !(id in symptomWeights))) throw new Error('Unknown symptom');
  return {
    pct: Math.min(100, selected.reduce((sum, id) => sum + symptomWeights[id], 0)),
    emergency: selected.some((id) => emergencySymptoms.has(id)),
  };
}

module.exports = { calculateRisk, symptomWeights };
