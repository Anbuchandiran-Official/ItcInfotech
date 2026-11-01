const fs = require('fs');
const path = require('path');

const root = __dirname;
const pptxPath = path.join(root, 'ITC_Infotech_Securing_Login_Page.pptx');
const credentialPath = path.join(root, 'cloudshare-568ae-firebase-adminsdk-fbsvc-a1057d11ee.json');

function readZip(file) {
  const buffer = fs.readFileSync(file);
  if (buffer.length < 22) throw new Error('Presentation is too small to be a ZIP package.');
  let eocd = -1;
  for (let p = buffer.length - 22, floor = Math.max(0, buffer.length - 65557); p >= floor; p--) {
    if (buffer.readUInt32LE(p) === 0x06054b50) { eocd = p; break; }
  }
  if (eocd < 0) throw new Error('ZIP central directory marker was not found.');
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const files = new Map();
  for (let i = 0; i < count; i++) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error('Invalid ZIP central directory entry.');
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    if (method !== 0) throw new Error(`Unsupported compression method ${method} in ${name}.`);
    files.set(name, compressed.toString('utf8'));
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return files;
}

function requireFile(files, file) {
  if (!files.has(file)) throw new Error(`Required package part is missing: ${file}`);
  return files.get(file);
}

function validate() {
  const files = readZip(pptxPath);
  const slideFiles = [...files.keys()].filter(name => /^ppt\/slides\/slide\d+\.xml$/.test(name));
  const noteFiles = [...files.keys()].filter(name => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(name));
  if (slideFiles.length !== 4) throw new Error(`Expected 4 slides, found ${slideFiles.length}.`);
  if (noteFiles.length !== 4) throw new Error(`Expected 4 speaker notes sections, found ${noteFiles.length}.`);

  const presentation = requireFile(files, 'ppt/presentation.xml');
  requireFile(files, 'ppt/notesMasters/notesMaster1.xml');
  const presentationRels = requireFile(files, 'ppt/_rels/presentation.xml.rels');
  if (!presentationRels.includes('/notesMaster') || !requireFile(files, '[Content_Types].xml').includes('/ppt/notesMasters/notesMaster1.xml')) {
    throw new Error('Notes master is not fully registered in the PowerPoint package.');
  }
  if ((presentation.match(/<p:sldId\b/g) || []).length !== 4) throw new Error('Presentation slide list does not contain exactly four slides.');
  for (let i = 1; i <= 4; i++) {
    const slide = requireFile(files, `ppt/slides/slide${i}.xml`);
    const notes = requireFile(files, `ppt/notesSlides/notesSlide${i}.xml`);
    if (!slide.includes('<p:sld ') || !slide.includes('ITC INFOTECH')) throw new Error(`Slide ${i} XML is missing expected content.`);
    if (!notes.includes('1-minute explanation') || !notes.includes('interviewer')) throw new Error(`Slide ${i} is missing detailed speaker notes.`);
    requireFile(files, `ppt/slides/_rels/slide${i}.xml.rels`);
    requireFile(files, `ppt/notesSlides/_rels/notesSlide${i}.xml.rels`);
  }

  const relFiles = [...files.entries()].filter(([name]) => name.endsWith('.rels'));
  for (const [name, source] of relFiles) {
    const ownerPath = name === '_rels/.rels' ? '' : name.replace(/\/_rels\//, '/').replace(/\.rels$/, '');
    const baseDir = path.posix.dirname(ownerPath);
    for (const match of source.matchAll(/Target="([^"]+)"/g)) {
      const target = match[1];
      if (/^[a-z]+:/i.test(target) || target.startsWith('#')) continue;
      const resolved = path.posix.normalize(path.posix.join(baseDir, target));
      if (!files.has(resolved)) throw new Error(`Broken relationship in ${name}: ${target} -> ${resolved}`);
    }
  }

  const credential = JSON.parse(fs.readFileSync(credentialPath, 'utf8').replace(/^\uFEFF/, ''));
  if (Object.keys(credential).length !== 0) throw new Error('Firebase JSON is expected to remain an empty object; do not put service-account keys in this workspace.');

  const slidesText = slideFiles.map(name => files.get(name)).join('\n');
  const textObjects = (slidesText.match(/<p:sp>/g) || []).length;
  const connectors = (slidesText.match(/<p:cxnSp>/g) || []).length;
  console.log('Presentation validation passed.');
  console.log(`Slides: ${slideFiles.length}; speaker notes: ${noteFiles.length}; shapes/text boxes: ${textObjects}; connectors: ${connectors}.`);
  console.log(`PPTX size: ${fs.statSync(pptxPath).size.toLocaleString()} bytes.`);
  console.log('Firebase JSON is valid and contains no credential fields.');
  console.log('All relationship targets resolve within the PowerPoint package.');
}

try { validate(); } catch (error) { console.error(`Validation failed: ${error.message}`); process.exitCode = 1; }
