export type Curve = 'secp256k1' | 'secp224r1';

export const curves = {
  secp224r1: 'secp224r1',
  secp256k1: 'secp256k1',
};
export const curvesMap: Record<string, Curve> = {
  'P-256K': 'secp256k1',
  'P-224': 'secp224r1',
  'secp224r1': 'secp224r1',
  'secp256k1': 'secp256k1',
};

export function normalizeCurveName(rawCurveName: string): Curve {
  const foundCurve = curvesMap[rawCurveName];
  if (!foundCurve) throw new Error(`Curve name: ${rawCurveName} not supported`);
  return foundCurve;
}

export const defaultCurve = curvesMap.secp256k1;
