'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateRisk } = require('../lib/risk');

test('returns zero when no symptoms are selected', () => {
  assert.deepEqual(calculateRisk([]), { pct: 0, emergency: false });
});

test('deduplicates symptoms and detects emergency indicators', () => {
  assert.deepEqual(calculateRisk(['neck', 'neck', 'fever']), { pct: 32, emergency: true });
});

test('caps the indicator at 100', () => {
  const result = calculateRisk(['fever', 'headache', 'neck', 'confusion', 'seizures', 'rash', 'unconscious']);
  assert.equal(result.pct, 100);
});

test('rejects unknown symptoms', () => {
  assert.throws(() => calculateRisk(['not-real']), /Unknown symptom/);
});
