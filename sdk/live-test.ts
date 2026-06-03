import { TollgateSigner } from './src/index.js';

async function main() {
  const tollgate = await TollgateSigner.create({
    notaryUrl:       'http://localhost:8080',
    agentToken:      'eyJhZ2VudF9pZCI6InRyYWRpbmctYm90LTAxIiwiaXNzdWVkX2F0IjoiMjAyNi0wNi0wM1QwOTo0MDowOFoiLCJleHBpcmVzX2F0IjoiMjAyNi0wNy0wM1QwOTo0MDowOFoiLCJ0b2tlbl9pZCI6ImM1MWI1NDFjLTJkMmMtNGRkMC05MzY1LWFjYTM5OWIxZDBhNiJ9.X0JZl_XVHSBNmjKaMtq_80XAFzlXw_MXWhX4ED4324g',
    agentId:         'trading-bot-01',
    safeAddress:     '0x76Db37E62F080Fe2EAa78DF9089b7daCb155A5A6',
    ownerPrivateKey: '0x5a5a8bf7b0034ded1b9cda5c4b20483666b9322481ad234426468045ccddc9f5',
  });

  console.log('✓ Connected to Notary');

  const result = await tollgate.simulate({
    to:        '0xdef4560000000000000000000000000000000000',
    value:     10000000n,
    amountUsd: 10.00,
    purpose:   'defi_yield_optimization',
  });

  console.log('✓ Result:', result.status);
  if (result.status === 'approved') {
    console.log('  Token ID :', result.approval_token.token_id);
    console.log('  Signature:', result.approval_token.signature.slice(0, 20) + '...');
  }
}

main().catch(console.error);