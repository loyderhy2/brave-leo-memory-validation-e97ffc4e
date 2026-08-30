const d = db.getSiblingDB('trrcsv');
const payloads = [
  ['plain_eq', '=1+1'],
  ['plain_plus', '+1+1'],
  ['plain_minus', '-1+1'],
  ['plain_at', '@SUM(1,1)'],
  ['space', ' =1+1'],
  ['tab', String.fromCharCode(9) + '=1+1'],
  ['cr', String.fromCharCode(13) + '=1+1'],
  ['lf', String.fromCharCode(10) + '=1+1'],
  ['vt', String.fromCharCode(11) + '=1+1'],
  ['ff', String.fromCharCode(12) + '=1+1'],
  ['nbsp', String.fromCharCode(160) + '=1+1'],
  ['bom', String.fromCharCode(0xFEFF) + '=1+1'],
  ['zwsp', String.fromCharCode(0x200B) + '=1+1']
];
for (const [label, payload] of payloads) {
  const collection = 'TRRCSV_' + label + '_' + payload;
  try {
    d.createCollection(collection);
    const document = { label: label, value: 1 };
    document['TRRCSV_FIELD_' + label + '_' + payload] = 1;
    d.getCollection(collection).insertOne(document);
    print('CREATED:' + label + ':' + tojson(collection));
  } catch (e) {
    print('FAILED:' + label + ':' + tojson(collection) + ':' + e);
  }
}
printjson(d.getCollectionNames());
