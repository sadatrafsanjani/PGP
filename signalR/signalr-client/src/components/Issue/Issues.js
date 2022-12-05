// rafce short cut for functional component

import React, { useEffect, useState } from "react";

function Issues() {
  // set states
  const [issueList, setIssueList] = useState();

  //useEffect() is to be used for side-effects executed in the render cycle
  useEffect(() => {
    //Console.log("Issues: useEffect");
    console.log("Issues: useEffect");
  }, []);

  function renderAllIssues() {
    //console.log("All issues");
    return (
      <table className="table table-striped">
        <thead>
          <tr>
            <th>Issue Id</th>
            <th>Code</th>
            <th>Title</th>
            <th>Created by</th>
            <th>Assign to</th>
          </tr>
        </thead>
      </table>
    );
  }

  return (
    <div>
      Issues
      {renderAllIssues()}
    </div>
  );
}

export default Issues;
