# Test Datasets

These are test datasets used for end to end testing.

## Naming Schemes

- All datasets start with `iam-data-` followed by an id.
- Within a dataset, the organizations are named `o-11111111`, `o-22222222`, etc.
- Account IDs start with the organization ID, and end with a sequential account number with zeros padded to 12 digits. For example:
  - `o-11111111` has accounts `100000000001`, `100000000002`, etc.
  - `o-22222222` has accounts `200000000001`, `200000000002`, etc.

## Usage

Use `getTestDatasetClient` to create a client using one of the datasets.
