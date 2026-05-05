-- Migration 008: Health check worker support
-- Adds 'waiting_health_check' to the job_status enum for pre-patch health gates.

ALTER TYPE job_status ADD VALUE IF NOT EXISTS 'waiting_health_check';
