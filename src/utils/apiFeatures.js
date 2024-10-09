class ApiFeatures {
  // Step 1: initialize the queryObject via a specific DB collection and url queryString from params
  constructor(queryObject, queryString) {
    this.queryObject = queryObject;
    this.queryString = queryString;
  }

  //* API Feature 1: Filter blogs by isPublished and category
  filterBlogs() {
    const copyQueryString = { ...this.queryString };

    // Remove some fields from copyQueryString to get the filter keywords
    const removeFields = ["page", "limit"];
    removeFields.forEach((key) => delete copyQueryString[key]);

    // Create query for isPublished and category
    const queryObj = {};
    if (copyQueryString?.isPublished !== undefined) {
      queryObj.isPublished = copyQueryString.isPublished === "true";
    }
    if (copyQueryString?.category) {
      queryObj.category = copyQueryString.category;
    }

    this.queryObject = this.queryObject.find(queryObj);
    return this;
  }

  //* API Feature 2: Pagination we want to show n document per page
  paginate(resultPerPage) {
    // Step 1: First create the query keyword (page)
    const currentPage = Number(this.queryString.page) || 1;
    const skipResult = resultPerPage * (currentPage - 1);

    // Step 2: get documents from DB collection
    this.queryObject = this.queryObject.limit(resultPerPage).skip(skipResult);
    return this;
  }
}

export { ApiFeatures };
