import express from 'express'
import {
  getFullBlockchain,
  tamperBlockForDemo,
  verifyFullBlockchain,
} from '../blockchain/blockchainService.js'

const router = express.Router()

router.get('/blockchain', async (req, res) => {
  try {
    const chain = await getFullBlockchain()

    return res.json({
      blocks: chain,
      total_blocks: chain.length,
    })
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    })
  }
})

router.get('/blockchain/verify', async (req, res) => {
  try {
    const result = await verifyFullBlockchain()

    return res.json(result)
  } catch (error) {
    return res.status(500).json({
      valid: false,
      error: error.message,
      invalid_index: null,
    })
  }
})

router.post('/blockchain/tamper/:index', async (req, res) => {
  try {
    const block = await tamperBlockForDemo(req.params.index)
    const verification = await verifyFullBlockchain()

    return res.json({
      message: 'Bloque modificado para demo.',
      block,
      verification,
    })
  } catch (error) {
    return res.status(400).json({
      error: error.message,
    })
  }
})

export default router