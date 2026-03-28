'use strict';

const crypto = require('crypto');

const STEANE_H = [
  [0,0,0,1,1,1,1],
  [0,1,1,0,0,1,1],
  [1,0,1,0,1,0,1],
];

const CODEWORDS = { 0:[0,0,0,0,0,0,0], 1:[1,1,1,0,0,0,0] };

const COSET_0 = [
  [0,0,0,0,0,0,0],[0,0,0,1,1,1,1],[0,0,1,0,1,1,0],[0,0,1,1,0,0,1],
  [0,1,0,0,1,0,1],[0,1,0,1,0,1,0],[0,1,1,0,0,1,1],[0,1,1,1,1,0,0]
];
const COSET_1 = [
  [1,0,0,0,0,1,1],[1,0,0,1,1,0,0],[1,0,1,0,1,0,1],[1,0,1,1,0,1,0],
  [1,1,0,0,1,1,0],[1,1,0,1,0,0,1],[1,1,1,0,0,0,0],[1,1,1,1,1,1,1]
];

class QuantumErrorCorrection {
  static encodeBit(bit) {
    if (bit !== 0 && bit !== 1) throw new Error('QEC: input must be 0 or 1');
    return [...CODEWORDS[bit]];
  }
  static encodeByte(byte) {
    const codewords = [];
    for (let i = 7; i >= 0; i--) codewords.push(QuantumErrorCorrection.encodeBit((byte>>i)&1));
    return codewords;
  }
  static encodeBuffer(buf) {
    const blocks = [];
    for (const byte of buf) blocks.push(...QuantumErrorCorrection.encodeByte(byte));
    return blocks;
  }
  static syndrome(codeword) {
    return STEANE_H.map(row => row.reduce((s,b,i) => s^(b&codeword[i]),0));
  }
  static syndromeToPosition(syn) {
    if (syn[0]===0&&syn[1]===0&&syn[2]===0) return -1;
    const val = (syn[2]<<2)|(syn[1]<<1)|syn[0];
    const lookup = {4:0,2:1,6:2,1:3,5:4,3:5,7:6};
    return lookup[val]!==undefined ? lookup[val] : -1;
  }
  static correct(codeword) {
    const syn = QuantumErrorCorrection.syndrome(codeword);
    const pos = QuantumErrorCorrection.syndromeToPosition(syn);
    const corrected = [...codeword];
    let errorCorrected = false;
    if (pos>=0&&pos<7) { corrected[pos]^=1; errorCorrected=true; }
    return { corrected, errorCorrected, errorPosition:pos };
  }
  static decodeBit(codeword) {
    const {corrected,errorCorrected,errorPosition} = QuantumErrorCorrection.correct(codeword);
    const inCoset0 = COSET_0.some(cw=>cw.every((b,i)=>b===corrected[i]));
    const inCoset1 = COSET_1.some(cw=>cw.every((b,i)=>b===corrected[i]));
    if (!inCoset0&&!inCoset1) return {bit:null,errorCorrected,errorPosition,uncorrectable:true};
    return {bit:inCoset1?1:0,errorCorrected,errorPosition,uncorrectable:false};
  }
  static decodeBuffer(blocks, originalLength) {
    const bytes=[]; let errors=0, uncorrectable=0;
    for (let b=0;b<blocks.length;b+=8) {
      let byte=0;
      for (let bit=0;bit<8;bit++) {
        const result=QuantumErrorCorrection.decodeBit(blocks[b+bit]);
        if (result.uncorrectable) uncorrectable++;
        if (result.errorCorrected) errors++;
        byte=(byte<<1)|(result.bit||0);
      }
      bytes.push(byte);
    }
    return {buffer:Buffer.from(bytes.slice(0,originalLength)),errorsFound:errors,uncorrectableErrors:uncorrectable};
  }
  static simulateError(codeword,position) { const e=[...codeword]; e[position]^=1; return e; }
  static generateBaseline(blocks) {
    const syndromes=blocks.map(b=>QuantumErrorCorrection.syndrome(b));
    const hash=crypto.createHash('sha256').update(JSON.stringify(syndromes)).digest('hex');
    return {syndromes,hash,blockCount:blocks.length,timestamp:Date.now()};
  }
  static verifyBaseline(blocks,baseline) {
    if (blocks.length!==baseline.blockCount) return {valid:false,score:1.0,reason:'Block count changed'};
    let mismatches=0;
    for (let i=0;i<blocks.length;i++) {
      const curr=QuantumErrorCorrection.syndrome(blocks[i]);
      if (curr.some((s,j)=>s!==baseline.syndromes[i][j])) mismatches++;
    }
    const score=mismatches/blocks.length;
    return {valid:score===0,score:parseFloat(score.toFixed(4)),mismatches,reason:score===0?'Integrity verified':`${mismatches} blocks disturbed`};
  }
}

module.exports = { QuantumErrorCorrection, STEANE_H, CODEWORDS };
