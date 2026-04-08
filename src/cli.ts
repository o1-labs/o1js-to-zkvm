#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import { Experimental, Field, initializeBindings } from 'o1js';
import { cubeRoot64 } from './cube-root.js';
import { importO1jsInternal } from './o1js-internal.js';

type OrInfinityJson = 'Infinity' | { x: string; y: string };

type CircuitDescription = {
  circuit: string;
  verificationKey: string;
  srs: OrInfinityJson[];
};

type ProofOutput = {
  circuit: string;
  proof: Experimental.KimchiJsonProof;
};

async function writeJson(filePath: string, data: unknown) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`);
}

const program = new Command()
  .name('o1js-cli')
  .description('CLI for compiling, proving, and verifying o1js circuits');

program
  .command('compile')
  .description('Compile the circuit and write its description to a JSON file')
  .requiredOption('-o, --output <file>', 'output JSON file')
  .action(async (opts: { output: string }) => {
    await initializeBindings();

    const { Pickles, wasm } = await importO1jsInternal('bindings.js');
    const { getRustConversion } = await importO1jsInternal(
      'bindings/crypto/bindings.js'
    );
    const { OrInfinity } = await importO1jsInternal(
      'bindings/crypto/bindings/curve.js'
    );
    const { MlArray } = await importO1jsInternal('lib/ml/base.js');

    console.log('Compiling...');
    const { verificationKey } = await cubeRoot64.compile();

    const rustConversion = getRustConversion(wasm);
    const wasmSrs = wasm.caml_fp_srs_get(Pickles.loadSrsFp());
    const mlSrs = rustConversion.fp.pointsFromRust(wasmSrs);
    const srs = MlArray.mapFrom(mlSrs, OrInfinity.toJSON);

    const description: CircuitDescription = {
      circuit: 'cube-root-64',
      verificationKey: verificationKey.toString(),
      srs,
    };

    await writeJson(opts.output, description);
    console.log(`Wrote circuit description to ${opts.output}`);
  });

program
  .command('prove')
  .description('Generate a proof from inputs and write it to a JSON file')
  .requiredOption(
    '-i, --input <file>',
    'input JSON file with public and private inputs'
  )
  .requiredOption('-o, --output <file>', 'output JSON file')
  .action(async (opts: { input: string; output: string }) => {
    await initializeBindings();

    const raw = await fs.readFile(opts.input, 'utf-8');
    const inputs = JSON.parse(raw) as {
      publicInput: string;
      privateInput: string;
    };

    const x = Field(inputs.publicInput);
    const y = Field(inputs.privateInput);

    console.log('Compiling...');
    await cubeRoot64.compile();

    console.log('Proving...');
    const proof = await cubeRoot64.prove(x, y);

    const output: ProofOutput = {
      circuit: 'cube-root-64',
      proof: proof.toJSON(),
    };

    await writeJson(opts.output, output);
    console.log(`Wrote proof to ${opts.output}`);
  });

program
  .command('verify')
  .description('Verify a proof against a circuit description')
  .requiredOption(
    '-c, --circuit <file>',
    'circuit description JSON (from compile)'
  )
  .requiredOption('-p, --proof <file>', 'proof JSON (from prove)')
  .action(async (opts: { circuit: string; proof: string }) => {
    await initializeBindings();

    const circuitRaw = await fs.readFile(opts.circuit, 'utf-8');
    const circuitDesc = JSON.parse(circuitRaw) as CircuitDescription;

    const proofRaw = await fs.readFile(opts.proof, 'utf-8');
    const proofOutput = JSON.parse(proofRaw) as ProofOutput;

    const vk = Experimental.KimchiVerificationKey.fromString(
      circuitDesc.verificationKey
    );
    const proof = Experimental.KimchiProof.fromJSON(proofOutput.proof);

    console.log('Verifying...');
    const ok = await proof.verify(vk);

    if (ok) {
      console.log('Proof is valid.');
    } else {
      console.error('Proof is invalid.');
      process.exit(1);
    }
  });

program.parse();
