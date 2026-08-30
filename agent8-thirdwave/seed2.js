const d = db.getSiblingDB('trrcsv');
const payloads = [
  ['plain_eq', '=1+1'],
  ['plain_plus', '+11+11'],
  ['plain_minus', '-12+12'],
  ['plain_at', '@SUM(13,13)'],
  ['space', ' =2+2'],
  ['tab', String.fromCharCode(9) + '=3+3'],
  ['cr', String.fromCharCode(13) + '=4+4'],
  ['lf', String.fromCharCode(10) + '=5+5'],
  ['vt', String.fromCharCode(11) + '=6+6'],
  ['ff', String.fromCharCode(12) + '=7+7'],
  ['nbsp', String.fromCharCode(160) + '=8+8'],
  ['bom', String.fromCharCode(0xFEFF) + '=9+9'],
  ['zwsp', String.fromCharCode(0x200B) + '=10+10']
];
for (const [label, payload] of payloads) {
  try {
    d.createCollection(payload);
    const document = { label: label, value: 1 };
    document[payload] = 1;
    d.getCollection(payload).insertOne(document);
    print('CREATED:' + label + ':' + tojson(payload));
  } catch (e) {
    print('FAILED:' + label + ':' + tojson(payload) + ':' + e);
  }
}
printjson(d.getCollectionNames());
