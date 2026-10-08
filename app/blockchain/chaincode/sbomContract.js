'use strict';

const { Contract } = require('fabric-contract-api');

class SBOMContract extends Contract {

    async createVerification(ctx, verificationId, proof, componentName, sbomHash, merkleRoot) {
        const exists = await this.verificationExists(ctx, verificationId);

        if (exists) {
            throw new Error(`Verification ${verificationId} already exists`);
        }

        const record = {
            verificationId,
            proof,
            componentName,
            sbomHash,
            merkleRoot,
            timestamp: new Date(ctx.stub.getTxTimestamp().seconds.low * 1000).toISOString()
        };

        await ctx.stub.putState(
            verificationId,
            Buffer.from(JSON.stringify(record))
        );

        return JSON.stringify(record);
    }

    async verificationExists(ctx, verificationId) {
        const record = await ctx.stub.getState(verificationId);
        return record && record.length > 0;
    }

    async readVerification(ctx, verificationId) {
        const exists = await this.verificationExists(ctx, verificationId);

        if (!exists) {
            throw new Error(`Verification ${verificationId} does not exist`);
        }

        const record = await ctx.stub.getState(verificationId);
        return record.toString();
    }
}

module.exports = SBOMContract;
